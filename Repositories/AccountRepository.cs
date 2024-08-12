using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Net8Angular17.Helpers;
using Net8Angular17.Models;
using Net8Angular17.Repositories;

namespace Net8Angular17.Properties
{
    public class AccountRepository : IAccountRepository
    {
        private UserManager<AppUser> _userManager;
        private RoleManager<IdentityRole> _roleManager;
        private IConfiguration _configuration;

        public AccountRepository(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager,
        IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthResponseModel> Register(RegisterModel registerModel)
        {
            if (registerModel == null)
            {
                throw new ArgumentNullException(nameof(registerModel));
            }

            var user = new AppUser
            {
                Email = registerModel.Email,
                FullName = registerModel.FullName,
                UserName = registerModel.Email
            };

            var result = await _userManager.CreateAsync(user, registerModel.Password);

            if (!result.Succeeded)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = string.Join(", ", result.Errors.Select(e => e.Description))
                };
            }

            await AssignRolesToUser(user, registerModel.Roles);

            return new AuthResponseModel
            {
                IsSuccess = true,
                Message = "Account Created Successfully!"
            };
        }

        public async Task<AuthResponseModel> Login(LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "Invalid email or password."
                };
            }

            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            int refreshTokenValidityInDays = GetRefreshTokenValidityInDays();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenValidityInDays);

            await _userManager.UpdateAsync(user);

            return new AuthResponseModel
            {
                Token = token,
                IsSuccess = true,
                Message = "Login Success.",
                RefreshToken = refreshToken
            };
        }

        public async Task<AuthResponseModel> RefreshToken(TokenModel tokenModel)
        {
            var principal = GetPrincipalFromExpiredToken(tokenModel.Token);
            var user = await _userManager.FindByEmailAsync(tokenModel.Email);

            if (principal == null || user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "Invalid client request"
                };
            }

            var newJwtToken = GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            int refreshTokenValidityInMinutes = GetRefreshTokenValidityInMinutes();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenValidityInMinutes);

            await _userManager.UpdateAsync(user);

            return new AuthResponseModel
            {
                IsSuccess = true,
                Token = newJwtToken,
                RefreshToken = newRefreshToken,
                Message = "Refreshed token successfully"
            };
        }

        public async Task<AuthResponseModel> ChangePassword(ChangePasswordModel changePasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(changePasswordModel.Email);
            if (user == null)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User does not exist with this email"
                };
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordModel.CurrentPassword, changePasswordModel.NewPassword);

            if (!result.Succeeded)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = result.Errors.FirstOrDefault()?.Description
                };
            }

            return new AuthResponseModel
            {
                IsSuccess = true,
                Message = "Password changed successfully"
            };
        }

        public async Task<AuthResponseModel> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            resetPasswordModel.Token = WebUtility.UrlDecode(resetPasswordModel.Token);

            if (user == null)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User does not exist with this email"
                };
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.NewPassword);
            if (!result.Succeeded)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = result.Errors.FirstOrDefault()?.Description
                };
            }

            return new AuthResponseModel
            {
                IsSuccess = true,
                Message = "Password reset successfully"
            };
        }

        private async Task AssignRolesToUser(AppUser user, IEnumerable<string> roles)
        {
            if (roles == null || roles.Contains(""))
            {
                if (!await _roleManager.RoleExistsAsync(AppRole.Customer))
                {
                    await _roleManager.CreateAsync(new IdentityRole(AppRole.Customer));
                }
                await _userManager.AddToRoleAsync(user, AppRole.Customer);
                return;
            }

            foreach (var role in roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    await _roleManager.CreateAsync(new IdentityRole(role));
                }
                await _userManager.AddToRoleAsync(user, role);
            }
        }

        public Task<IdentityResult> GetUserDetail()
        {
            throw new NotImplementedException();
        }
        public async Task<UserDetailModel> GetUserDetailAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user is null)
            {
                return null; // or throw an exception
            }

            var roles = await _userManager.GetRolesAsync(user);

            return new UserDetailModel
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = roles.ToArray(),
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount
            };
        }

        public async Task<IEnumerable<UserDetailModel>> GetUsersAsync()
        {
            var users = await _userManager.Users
                .Select(u => new 
                {
                    u.Id,
                    u.Email,
                    u.FullName
                }).ToListAsync();

            var userDetailModels = new List<UserDetailModel>();
            foreach (var user in users)
            {
                var appUser = new AppUser { Id = user.Id, Email = user.Email, FullName = user.FullName };
                var roles = await _userManager.GetRolesAsync(appUser);
                userDetailModels.Add(new UserDetailModel
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = roles.ToArray()
                });
            }

            return userDetailModels;
        }
    
        private async Task<GoogleJsonWebSignature.Payload> ValidateGoogleTokenAsync(string idToken)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings()
                {
                    Audience = new List<string>() { _configuration["Google:ClientId"] }
                };
                var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, settings);
                return payload;
            }
            catch (Exception)
            {
                return null;
            }
        }
        private async Task EnsureCustomerRoleExists()
        {
            if (!await _roleManager.RoleExistsAsync(AppRole.Customer))
            {
                await _roleManager.CreateAsync(new IdentityRole(AppRole.Customer));
            }
        }

        private int GetRefreshTokenValidityInMinutes()
        {
            return int.TryParse(_configuration.GetSection("JWT:RefreshTokenValidityInMinutes").Value, out int minutes) ? minutes : 1440; // Default to 1 day
        }
        private string GenerateToken(AppUser user){
            var tokenHandler = new JwtSecurityTokenHandler();
            
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JWT").GetSection("securityKey").Value!);

            var roles = _userManager.GetRolesAsync(user).Result;

            List<Claim> claims = 
            [
                new (JwtRegisteredClaimNames.Email,user.Email??""),
                new (JwtRegisteredClaimNames.Name,user.FullName??""),
                new (JwtRegisteredClaimNames.NameId,user.Id ??""),
                new (JwtRegisteredClaimNames.Aud,_configuration.GetSection("JWT").GetSection("validAudience").Value!),
                new (JwtRegisteredClaimNames.Iss,_configuration.GetSection("JWT").GetSection("validIssuer").Value!)
            ];


            foreach(var role in roles)

            {
                claims.Add(new Claim(ClaimTypes.Role,role.ToString()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            };


            var token  = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JWT").GetSection("securityKey").Value!)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        private int GetRefreshTokenValidityInDays()
        {
            return int.TryParse(_configuration.GetSection("JWT:RefreshTokenValidityInDays").Value, out int days) ? days : 1; // Default to 1 day
        }

        public async Task<AuthResponseModel> GoogleLogin(GoogleLoginModel googleLoginModel)
        {
            if (googleLoginModel == null || string.IsNullOrEmpty(googleLoginModel.IdToken))
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User not found with this email",
                };
            }

            var validatedToken = await ValidateGoogleTokenAsync(googleLoginModel.IdToken);
            if (validatedToken == null)
            {
                return new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "Invalid Google token."
                };
            }

            var user = await _userManager.FindByEmailAsync(validatedToken.Email);
            if (user == null)
            {
                user = new AppUser
                {
                    Email = validatedToken.Email,
                    FullName = validatedToken.Name,
                    UserName = validatedToken.Email
                };

                var createResult = await _userManager.CreateAsync(user, "Abc@123");
                if (!createResult.Succeeded)
                {
                    return new AuthResponseModel
                    {
                        IsSuccess = false,
                        Message = string.Join(", ", createResult.Errors.Select(e => e.Description))
                    };
                }

                await EnsureCustomerRoleExists();
                await _userManager.AddToRoleAsync(user, AppRole.Customer);
            }

            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(GetRefreshTokenValidityInMinutes());

            await _userManager.UpdateAsync(user);

            return new AuthResponseModel
            {
                IsSuccess = true,
                Message = "Login successful.",
                Token = token,
                RefreshToken = refreshToken
            };
        }

    }
}