using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JWTRefreshTokenNet8.Repos
{
    public interface ITokenService
    {

        public JwtSecurityToken CreateToken(List<Claim> authClaims);
        public string GenerateRefreshToken();

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);

    }
}
