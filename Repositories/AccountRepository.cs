using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
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

        public Task<IdentityResult> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> GetUserDetail()
        {
            throw new NotImplementedException();
        }

        public Task<AuthResponseModel> Login(LoginModel loginModel)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> Register(RegisterModel registerModel)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            throw new NotImplementedException();
        }
    }
}