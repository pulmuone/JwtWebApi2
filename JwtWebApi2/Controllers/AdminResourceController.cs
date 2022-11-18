using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtWebApi2.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminResourceController : ControllerBase
    {
        [Route("adminResource")]
        [HttpGet]
        //[AllowAnonymous]
        public IActionResult Get()
        {
            return Ok($"This resource is granted to the role of");
        }
    }
}
