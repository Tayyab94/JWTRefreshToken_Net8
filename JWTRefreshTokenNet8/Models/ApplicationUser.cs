using Microsoft.AspNetCore.Identity;

namespace JWTRefreshTokenNet8.Models
{
    public class ApplicationUser :IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
