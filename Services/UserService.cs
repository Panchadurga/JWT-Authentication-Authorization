using JWTAuthentication.Data;
using JWTAuthentication.Models;
using JWTAuthentication.Services.Helper;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Services;

public class UserService
{
    private readonly ApplicationDbContext _context;

    public UserService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<ApplicationUser?> ValidateUserAsync(string username, string password)
    {
        var user = await _context.User.SingleOrDefaultAsync(u => u.Username == username);
        if (user == null || !PasswordHasher.VerifyPassword(password, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Invalid username or password.");
        }
        return user;
    }

    public async Task<ApplicationUser?> FindByUsernameAsync(string username)
    {
        return await _context.User.SingleOrDefaultAsync(u => u.Username == username);
    }

}
