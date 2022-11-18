using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace JwtWebApi2.Controllers
{
    [Authorize(Roles = "User, Admin")]
    public class ProtectedResourceController : ControllerBase
    {
        [Route("protectedInfo")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Get()
        {
            return Ok("You can see this message means you are a valid user.");
        }
    }
}
