using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Net8Angular17.Models
{
    public class TokenModel
    {
        public string RefreshToken { get; set; } = null!;
        public string Token { get; set; } = null!;
        public string Email { get; set; } = null!;
    }
}