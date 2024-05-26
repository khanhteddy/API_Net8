using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Net8Angular17.Models
{
    public class CreateRoleModel
    {
        [Required(ErrorMessage ="Role Name is required.")]
        public string RoleName { get; set; } = null!;
    }
}