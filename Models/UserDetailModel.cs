using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Net8Angular17.Models
{
    public class UserDetailModel
    {
        public string? Id { get; set; }
        public string? FullName { get; set; }
        public string? Email { get; set; }
        public string[]? Roles { get; set; }
        public string? PhoneNumber { get; set; }
        public bool TwoFacotrEnabled { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public int AccessFailedCount { get; set; }
    }
}