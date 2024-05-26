using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8Angular17.Helpers;
using Net8Angular17.Models;

namespace Net8Angular17.Controllers
{
    [Authorize(Roles = AppRole.Admin)]
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;

        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
        {
            _roleManager = roleManager;
            _userManager=userManager;
        }


        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleModel createRoleModel)
        {
            if(string.IsNullOrEmpty(createRoleModel.RoleName))
            {
                return BadRequest("Role name is required");
            }

            var roleExist = await _roleManager.RoleExistsAsync(createRoleModel.RoleName);

            if(roleExist)
            {
                return BadRequest("Role already exist");
            }

            // var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

            // if(roleResult.Succeeded)
            // {
            //     return Ok(new {message="Role Created successfully"});
            // }
            switch (createRoleModel.RoleName)
                    {
                        case "Admin":
                            
                            if (!await _roleManager.RoleExistsAsync(AppRole.Admin))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Admin));
                            }
                            break;

                        case "Manager":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Manager))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Manager));
                            }
                            break;
                        case "HR":
                            if (!await _roleManager.RoleExistsAsync(AppRole.HR))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.HR));
                            }
                            break;
                        case "Accountant":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Accountant))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Accountant));
                            }
                            break;
                        case "Warehouse":
                            if (!await _roleManager.RoleExistsAsync(AppRole.Warehouse))
                            {
                                await _roleManager.CreateAsync(new IdentityRole(AppRole.Warehouse));
                            }
                            break;
                        default:
                            // Optionally, handle other roles or log unexpected values
                            break;
                    }

            return BadRequest("Role creation failed.");
            
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseModel>>> GetRoles()
        {
            var roles = await _roleManager.Roles.ToListAsync();

            var roleModels = new List<RoleResponseModel>();

            foreach (var role in roles)
            {
                var userCount = (await _userManager.GetUsersInRoleAsync(role.Name)).Count;
                
                var roleModel = new RoleResponseModel
                {
                    Id = role.Id,
                    Name = role.Name,
                    TotalUsers = userCount
                };

                roleModels.Add(roleModel);
            }

            return Ok(roleModels);
        }



        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            // find role by their id

            var role = await _roleManager.FindByIdAsync(id);

            if(role is null)
            {
                return NotFound("Role not found.");
            }

            var result = await _roleManager.DeleteAsync(role);

            if(result.Succeeded)
            {
                return Ok( new {message="Role deleted successfully."});
            }

            return BadRequest("Role deletion failed.");
            
        }


        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignModel roleAssignModel)
        {
            var user = await _userManager.FindByIdAsync(roleAssignModel.UserId);

            if(user is null)
            {
                return NotFound("User not found.");
            }

            var role =await _roleManager.FindByIdAsync(roleAssignModel.RoleId);

            if(role is null)

            {
                return NotFound("Role not found.");
            }

            var result = await _userManager.AddToRoleAsync(user,role.Name!);

            if(result.Succeeded)
            {
                return Ok(new {message="Role assigned successfully"});
            }

            var error = result.Errors.FirstOrDefault();

            return BadRequest(error!.Description);

        }


    }
}