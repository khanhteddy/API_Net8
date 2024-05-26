using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Net8Angular17.Models
{
    public class RegisterModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty; 

        [Required]
        public string FullName { get; set; } = string.Empty;

        public string   Password { get; set; } = string.Empty;

        public List<string>? Roles { get; set; }
    }
}