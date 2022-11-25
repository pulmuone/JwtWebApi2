using JwtWebApi2.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtWebApi2.Controllers
{
    [ApiController]
    public class TokenController : ControllerBase
    {
        // Key: userName; Guid: refresh token value.
        // Recommend to persistent this alone with the user records.
        // Based on the scenario, you might have 1 user, 1 refresh token or 1 user, multiple refresh tokens.
        static readonly ConcurrentDictionary<string, Guid> _refreshToken = new ConcurrentDictionary<string, Guid>();
        private readonly IConfiguration _configuration;
        private readonly ILogger<TokenController> _logger;

        public TokenController(IConfiguration configuration, ILogger<TokenController> logger)
        {
            _configuration = configuration;
            this._logger = logger;
        }

        // Returns an JWT token when the login info is valid.
        /// <summary>
        /// 로그인
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        [Route("token")]
        [HttpPost()]
        public IActionResult GetToken([FromBody] UserContract login)
        {
            _logger.LogInformation($"Registration Attempt for {login.UserName}");

            int abc = 0;

            //var temp = 10 / abc;

            AuthenticationResult authenticationResult = GetAuthenticationResult(login);

            if (authenticationResult is null)
            {
                return Forbid();
            }

            return Ok(authenticationResult);
        }

        [Route("refresh")]
        [HttpPost()]
        public IActionResult RefreshToken([FromBody] AuthenticationResult oldResult)
        {
            if (!IsValid(oldResult, out string validUserName))
            {
                return Forbid();
            }
            return Ok(CreateAuthResult(validUserName));
        }

        [Route("revoke/{userName}")]
        [HttpPost]
        public IActionResult RevokeRefreshToken(string userName)
        {
            if (_refreshToken.TryRemove(userName, out _))
            {
                return NoContent();
            }
            return BadRequest("User doesn't exist");
        }

        /// <summary>
        /// Returns an access token when the login is valid. Returns null otherwise;
        /// </summary>
        private AuthenticationResult GetAuthenticationResult(UserContract login)
        {
            if (!IsValid(login))
            {
                return null;
            }

            //로그인이 성공했다는 가정하에 토큰을 생성한다.
            return CreateAuthResult(login.UserName);
        }

        /// <summary>
        /// 토큰 생성, GenerateToken
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        private AuthenticationResult CreateAuthResult(string userName)
        {
            // Package: System.IdentityModel.Tokens.Jwt
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            DateTime expiry = DateTime.Now.AddMinutes(Convert.ToInt32(_configuration["JwtSettings:DurationInMinutes"]));

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userName)
            };

            //Role이 Multi일 경우
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            claims.Add(new Claim(ClaimTypes.Role, "Manager"));
            claims.Add(new Claim(ClaimTypes.Role, "Worker"));

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToInt32(_configuration["JwtSettings:DurationInMinutes"])),
                signingCredentials: credentials
                );

            return new AuthenticationResult
            {
                AccessToken = (new JwtSecurityTokenHandler()).WriteToken(token),
                RefreshToken = GenerateRefreshToken(userName),
                Expiry = expiry,
            };
        }

        private bool IsValid(UserContract login)
            => string.Equals(login?.UserName, "gwise", StringComparison.OrdinalIgnoreCase) && string.Equals(login?.Password, "1234", StringComparison.Ordinal);

        private bool IsValid(AuthenticationResult authResult, out string validUserName)
        {
            validUserName = string.Empty;

            ClaimsPrincipal principal = GetPrincipalFromExpiredToken(authResult.AccessToken);
            if (principal is null)
            {
                return false;
            }

            validUserName = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(validUserName))
            {
                return false;
            }

            if (!Guid.TryParse(authResult.RefreshToken, out Guid givenRefreshToken))
            {
                return false;
            }

            if (!_refreshToken.TryGetValue(validUserName, out Guid currentRefreshToken))
            {
                return false;
            }

            if (currentRefreshToken != givenRefreshToken)
            {
                return false;
            }

            return true;
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken)
        {
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"])),
                ValidateLifetime = false,
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        private string GenerateRefreshToken(string userName)
        {
            Guid newRefreshToken = _refreshToken.AddOrUpdate(userName, (u) => Guid.NewGuid(), (k, old) => Guid.NewGuid());
            return newRefreshToken.ToString("D");
        }
    }
}
