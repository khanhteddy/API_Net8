using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Net8Angular17.Models;

namespace Net8Angular17.Repositories
{
    public interface IAccountRepository
    {
        public Task<IdentityResult> Register (RegisterModel registerModel);
        public Task<AuthResponseModel> Login (LoginModel loginModel);
        public Task<IdentityResult> ForgotPassword (ForgotPasswordModel forgotPasswordModel);
        public Task<IdentityResult> ResetPassword (ResetPasswordModel resetPasswordModel);
        public Task<IdentityResult> GetUserDetail();
    }
}