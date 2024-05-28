using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Net8Angular17.Helpers;
using Net8Angular17.Models;
using RestSharp;

namespace Net8Angular17.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;


        public AccountController(UserManager<AppUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterModel registerModel)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new AppUser {
                Email = registerModel.Email,
                FullName = registerModel.FullName,
                UserName = registerModel.Email
            };

            var result = await _userManager.CreateAsync(user,registerModel.Password);

            if(!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            
            if(registerModel.Roles is null){
                    //await _userManager.AddToRoleAsync(user,"User");
                if (!await _roleManager.RoleExistsAsync(AppRole.Customer))
				{
					await _roleManager.CreateAsync(new IdentityRole(AppRole.Customer));
				}
				await _userManager.AddToRoleAsync(user, AppRole.Customer);
            }
            else
            {
                foreach (var role in registerModel.Roles)
                {
                    switch (role)
                    {
                        case "Admin":
                            
                            if (!await _roleManager.RoleExistsAsync(AppRole.Admin))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Admin));
                            }
                            await _userManager.AddToRoleAsync(user, AppRole.Admin);
                            break;

                        case "Manager":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Manager))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Manager));
                            }
                            await _userManager.AddToRoleAsync(user, AppRole.Manager);
                            break;
                        case "HR":
                            if (!await _roleManager.RoleExistsAsync(AppRole.HR))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.HR));
                            }
                            await _userManager.AddToRoleAsync(user, AppRole.HR);
                            break;
                        case "Accountant":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Accountant))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Accountant));
                            }
                            await _userManager.AddToRoleAsync(user, AppRole.Accountant);
                            break;
                        case "Warehouse":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Warehouse))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Warehouse));
                            }
                            await _userManager.AddToRoleAsync(user, AppRole.Warehouse);
                            break;
                        default:
                            // Optionally, handle other roles or log unexpected values
                            await _userManager.AddToRoleAsync(user, AppRole.Customer);
                            break;
                    }
                }

            }
            
        return Ok(new AuthResponseModel{
            IsSuccess = true,
            Message = "Account Created Sucessfully!"
        });

        }

        //api/account/login
        [AllowAnonymous]
        [HttpPost("login")]

        public async Task<ActionResult<AuthResponseModel>> Login(LoginModel loginModel)
        {
            if(!ModelState.IsValid)
            {
               return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginModel.Email);

            if(user is null)
            {
                return Unauthorized(new AuthResponseModel{
                    IsSuccess = false,
                    Message = "User not found with this email",
                });
            }

            var result = await _userManager.CheckPasswordAsync(user,loginModel.Password);

            if(!result){
                return Unauthorized(new AuthResponseModel{
                    IsSuccess=false,
                    Message= "Invalid Password."
                });
            }

            
            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration.GetSection("JWT").GetSection("RefreshTokenValidityInDays").Value!, out int RefreshTokenValidityInDays);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenValidityInDays);
            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponseModel{
                Token = token,
                IsSuccess = true,
                Message = "Login Success.",
                RefreshToken = refreshToken
            });
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]

        public async Task<ActionResult<AuthResponseModel>> RefreshToken(TokenModel token)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var principal = GetPrincipalFromExpiredToken(token.Token);
            var user = await _userManager.FindByEmailAsync(token.Email);

            if (principal is null || user is null || user.RefreshToken != token.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
                return BadRequest(new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "Invalid client request"
                });

            var newJwtToken = GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration.GetSection("JWTSetting").GetSection("RefreshTokenValidityIn").Value!, out int RefreshTokenValidityIn);

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenValidityIn);

            await _userManager.UpdateAsync(user);

            return Ok(new AuthResponseModel
            {
                IsSuccess = true,
                Token = newJwtToken,
                RefreshToken = newRefreshToken,
                Message = "Refreshed token successfully"
            });
        }

        [HttpPost("change-password")]
        public async Task<ActionResult> ChangePassword(ChangePasswordModel changePasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(changePasswordModel.Email);
            if (user is null)
            {
                return BadRequest(new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User does not exist with this email"
                });
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordModel.CurrentPassword, changePasswordModel.NewPassword);

            if (result.Succeeded)
            {
                return Ok(new AuthResponseModel
                {
                    IsSuccess = true,
                    Message = "Password changed successfully"
                });
            }

            return BadRequest(new AuthResponseModel
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()!.Description
            });
        }


        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            resetPasswordModel.Token = WebUtility.UrlDecode(resetPasswordModel.Token);

            if (user is null)
            {
                return BadRequest(new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User does not exist with this email"
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new AuthResponseModel
                {
                    IsSuccess = true,
                    Message = "Password reset Successfully"
                });
            }

            return BadRequest(new AuthResponseModel
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()!.Description
            });
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

        //api/account/detail
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailModel>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(currentUserId!);


            if(user is null)
            {
                return NotFound(new AuthResponseModel{
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            return Ok(new UserDetailModel{
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = [..await _userManager.GetRolesAsync(user)],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount,

            });

        }


        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailModel>>> GetUsers()
        {
            // Fetch users first
            var users = await _userManager.Users
                .Select(u => new 
                {
                    u.Id,
                    u.Email,
                    u.FullName
                }).ToListAsync();

            // Fetch roles for each user
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

            return Ok(userDetailModels);
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

    }
}