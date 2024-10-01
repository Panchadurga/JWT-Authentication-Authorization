using JWTAuthentication.Data;
using JWTAuthentication.Dtos;
using JWTAuthentication.Models;
using JWTAuthentication.Services;
using JWTAuthentication.Services.Helper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Controllers;


[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly JwtService _jwtService;
    private readonly UserService _userService;
    private readonly ApplicationDbContext _context;

    public AuthController(JwtService jwtService, UserService userService, ApplicationDbContext context)
    {
        _jwtService = jwtService;
        _userService = userService;
        _context = context;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequestDto request)
    {
        var user = await _userService.ValidateUserAsync(request.Username, request.Password);
        if (user == null)
            return Unauthorized();

        var jwtToken = _jwtService.GenerateToken(user);
        var refreshToken = _jwtService.GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
        await _context.SaveChangesAsync();

        return Ok(new AuthResponseDto { Token = jwtToken, RefreshToken = refreshToken });
    }

    [HttpGet("token-data")]
    [Authorize]
    public IActionResult GetTokenData()
    {
        var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

        // You can use the token for further validation or processing as needed
        return Ok(new { token });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequestDto request)
    {
        var user = await _context.User.SingleOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
        if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)
            return Unauthorized("Invalid or expired refresh token");

        var newJwtToken = _jwtService.GenerateToken(user);
        var newRefreshToken = _jwtService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
        await _context.SaveChangesAsync();

        return Ok(new AuthResponseDto { Token = newJwtToken, RefreshToken = newRefreshToken });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequestDto request)
    {
        // Check if the username already exists
        var existingUser = await _userService.FindByUsernameAsync(request.Username);
        if (existingUser != null)
        {
            return BadRequest(new { message = "Username already exists." });
        }

        // Create the user
        var user = new ApplicationUser
        {
            Username = request.Username,
            PasswordHash = PasswordHasher.HashPassword(request.Password) 
        };

        await _context.User.AddAsync(user);
        await _context.SaveChangesAsync();

        return Ok(new { message = "User registered successfully." });
    }

}
