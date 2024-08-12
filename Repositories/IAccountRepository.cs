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
        // public Task<IdentityResult> ForgotPassword (ForgotPasswordModel forgotPasswordModel);
        Task<IdentityResult> GetUserDetail();
        Task<AuthResponseModel> Register(RegisterModel registerModel);
        Task<AuthResponseModel> Login(LoginModel loginModel);
        Task<AuthResponseModel> RefreshToken(TokenModel tokenModel);
        Task<AuthResponseModel> ChangePassword(ChangePasswordModel changePasswordModel);
        Task<AuthResponseModel> ResetPassword(ResetPasswordModel resetPasswordModel);
        Task<AuthResponseModel> GoogleLogin(GoogleLoginModel googleLoginModel);
        Task<UserDetailModel> GetUserDetailAsync(string userId);
        Task<IEnumerable<UserDetailModel>> GetUsersAsync();
    }
}