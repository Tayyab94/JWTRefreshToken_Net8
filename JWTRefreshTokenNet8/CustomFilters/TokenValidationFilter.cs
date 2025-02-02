using JWTRefreshTokenNet8.Repos;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.IdentityModel.Tokens.Jwt;

namespace JWTRefreshTokenNet8.CustomFilters
{
    public class TokenValidationFilter : IAsyncActionFilter
    {
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _configuration;

        public TokenValidationFilter(ITokenService tokenService, IConfiguration configuration)
        {
            this._configuration = configuration;
            this._tokenService = tokenService;
        }


        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var authHeader= context.HttpContext.Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Result = new UnauthorizedResult();
                return;
            }
            
            var token= authHeader.Substring("Bearer ".Length).Trim();
            var handler= new JwtSecurityTokenHandler();

            if(!handler.CanReadToken(token))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var jwtToken= handler.ReadJwtToken(token);
            var expireDate = jwtToken.ValidTo;


            // check if the token is expire
            if(expireDate < DateTime.UtcNow)
            {
               var refreshToken= context.HttpContext.Request.Headers["RefreshToken"].ToString();
                if(string.IsNullOrEmpty(refreshToken))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                // Refresh the Token 

                var principal = _tokenService.GetPrincipalFromExpiredToken(token);
                var userName= principal.Identity.Name;

                if (!ValidateRefreshToken(refreshToken, userName))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                // GenerateNewToken

                var newGeneratedAccessToken = _tokenService.CreateToken(principal.Claims.ToList());
                var newRefreshToken = _tokenService.GenerateRefreshToken();

                // Attach the new tokens to the response headers

                // context.HttpContext.Response.Headers.Add("AccessToken", newGeneratedAccessToken.ToString());
                context.HttpContext.Response.Headers["AccessToken"] = new JwtSecurityTokenHandler().WriteToken(newGeneratedAccessToken);

                context.HttpContext.Response.Headers.Add("RefreshToken", newRefreshToken);

                var accessToken= handler.WriteToken(newGeneratedAccessToken);
                context.HttpContext.Response.Headers["Authorization"] =$"Bearer {accessToken}";
            }

            await next();

        }

        private bool ValidateRefreshToken(string refreshToken, string userName)
        {
            return true;
        }
    }
}
