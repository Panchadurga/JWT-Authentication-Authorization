using JWTAuthentication.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthentication.Services;

public class JwtService
{
    private readonly string _jwtSecret;
    private readonly int _jwtLifespan;
    private readonly string _audience;

    public JwtService(IConfiguration config)
    {
        // Check for null and throw an exception if the keys are missing
        _jwtSecret = config["JwtConfig:Secret"] ?? throw new ArgumentNullException("JwtConfig:Secret is not configured.");

        // Parse lifespan and provide a default value or throw an exception if null
        if (!int.TryParse(config["JwtConfig:Lifespan"], out _jwtLifespan))
        {
            throw new ArgumentException("JwtConfig:Lifespan is not a valid integer.");
        }
        _audience = config["JwtConfig:Audience"] ?? throw new ArgumentNullException("JwtConfig:Audience is not configured.");
    }

    public string GenerateToken(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSecret);

        // Create claims
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Aud, _audience), // Audience
            new Claim(JwtRegisteredClaimNames.Iss, "https://localhost:7277/"), // Issuer
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), // Subject
            new Claim(JwtRegisteredClaimNames.Name, user.Username), // Full name
            new Claim(JwtRegisteredClaimNames.Email, user.Email), // Email
            new Claim(JwtRegisteredClaimNames.Exp, DateTime.UtcNow.AddMinutes(_jwtLifespan).ToString()), // Expiration
            new Claim(JwtRegisteredClaimNames.Nbf, DateTime.UtcNow.ToString()), // Not Before
            new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()), // Issued At
            new Claim(JwtRegisteredClaimNames.Typ,"Bearer")
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtLifespan),
            IssuedAt = DateTime.UtcNow, // Issued At
            NotBefore = DateTime.UtcNow, // Not Before
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }

}
