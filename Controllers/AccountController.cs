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
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Net8Angular17.Data;
using Net8Angular17.Helpers;
using Net8Angular17.Models;
using Net8Angular17.Properties;
using Net8Angular17.Repositories;
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
        private readonly IAccountRepository _accountRepository;
        private readonly ICacheRepository _cacheRepository;
        private readonly DataContext _context;


        // private readonly AccountRepository _authService;

        public AccountController(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IAccountRepository accountRepository,
            ICacheRepository cacheRepository,
            DataContext context
        )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _accountRepository = accountRepository;
            _cacheRepository = cacheRepository;
            _context = context;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<AuthResponseModel>> Register(RegisterModel registerModel)
        {
            var response = await _accountRepository.Register(registerModel);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseModel>> Login(LoginModel loginModel)
        {
            var response = await _accountRepository.Login(loginModel);
            if (!response.IsSuccess)
            {
                return Unauthorized(response);
            }

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthResponseModel>> RefreshToken(TokenModel token)
        {
            var response = await _accountRepository.RefreshToken(token);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }

            return Ok(response);
        }

        [HttpPost("change-password")]
        public async Task<ActionResult<AuthResponseModel>> ChangePassword(ChangePasswordModel changePasswordModel)
        {
            var response = await _accountRepository.ChangePassword(changePasswordModel);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<ActionResult<AuthResponseModel>> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            var response = await _accountRepository.ResetPassword(resetPasswordModel);
            if (!response.IsSuccess)
            {
                return BadRequest(response);
            }

            return Ok(response);
        }

        //api/account/detail
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailModel>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userDetail = await _accountRepository.GetUserDetailAsync(currentUserId);

            if (userDetail is null)
            {
                return NotFound(new AuthResponseModel
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            return Ok(userDetail);
        }


        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailModel>>> GetUsers()
        {
            var users = await _accountRepository.GetUsersAsync();
            return Ok(users);
        }

        [AllowAnonymous]
        [HttpPost("google-login")]
        public async Task<ActionResult<AuthResponseModel>> GoogleLogin(GoogleLoginModel googleLoginModel)
        {
            var response = await _accountRepository.GoogleLogin(googleLoginModel);
            if (!response.IsSuccess)
            {
                return Unauthorized(response);
            }

            return Ok(response);
        }
        [AllowAnonymous]
        [HttpGet("driver")]
        public async Task<IActionResult> Get()
        {
            var cacheData = _cacheRepository.GetData<IEnumerable<Drive>>("drive");
            if (cacheData != null && cacheData.Count() > 0)
            {
                return Ok(cacheData);
            }

            cacheData = await _context.Drive.ToListAsync();
            var expriryTime = DateTimeOffset.Now.AddSeconds(15);
            _cacheRepository.SetData<IEnumerable<Drive>>("drive", cacheData, expriryTime);
            
            return Ok(cacheData);
        }
        [AllowAnonymous]
        [HttpPost("addDrive")]
        public async Task<IActionResult> Post(Drive value)
        {
            var addObject = await _context.Drive.AddAsync(value);
            var expriryTime = DateTimeOffset.Now.AddSeconds(30);
            _cacheRepository.SetData<Drive>($"drive{value.Id}", addObject.Entity, expriryTime);
            await _context.SaveChangesAsync();
            return Ok(addObject.Entity);
        }
        [AllowAnonymous]
        [HttpDelete("deleteDrive")]
        public async Task<IActionResult> Delete(int id)
        {
            var exist = _context.Drive.FirstOrDefaultAsync(x => x.Id == id);
            if (exist != null)
            {
                _context.Remove(exist);
                _cacheRepository.RemoveData($"drive{id}");
                return NoContent();
            }

            return NotFound();
        }
    }
}