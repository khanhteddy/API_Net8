using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
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

        public async Task<ActionResult<AuthResponseModel>> Login(LoginModel loginDto)
        {
            if(!ModelState.IsValid)
            {
               return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if(user is null)
            {
                return Unauthorized(new AuthResponseModel{
                    IsSuccess = false,
                    Message = "User not found with this email",
                });
            }

            var result = await _userManager.CheckPasswordAsync(user,loginDto.Password);

            if(!result){
                return Unauthorized(new AuthResponseModel{
                    IsSuccess=false,
                    Message= "Invalid Password."
                });
            }

            
            var token = GenerateToken(user);

            return Ok(new AuthResponseModel{
                Token = token,
                IsSuccess = true,
                Message = "Login Success."
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
            var users = await _userManager.Users.Select(u=> new UserDetailModel{
                Id = u.Id,
                Email=u.Email,
                FullName=u.FullName,
                //Roles=_userManager.GetRolesAsync(u).Result.ToArray()
            }).ToListAsync();

            return Ok(users);
        }
    }
}