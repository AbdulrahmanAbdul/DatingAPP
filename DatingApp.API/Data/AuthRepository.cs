using System.Threading.Tasks;
using DatingApp.API.Models;
using System.Security.Cryptography;
using System;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;
        public AuthRepository(DataContext context)
        {
            _context = context;
        }
        public async Task<User> Login(string username, string password)
        {
            var foundUser = await _context.Users.FirstOrDefaultAsync(x => x.Username == username);

            if(foundUser == null)
                return null;

            if(VerifyPasswordHash(password, foundUser.PasswordHash, foundUser.PasswordSalt))
                return foundUser;
            return null;
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var compHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                for (int i = 0; i < compHash.Length; i++)
                {
                    if(passwordHash[i] != compHash[i])
                        return false;  
                }
            }
                return true;
                //return compHash == passwordHash;

        }

        public async Task<User> Register(User user, string password)
        {
           byte[] passwordHash, passwordSalt;
           
           HashPassword(password,out passwordHash,out passwordSalt);

           user.PasswordHash = passwordHash;
           user.PasswordSalt = passwordSalt;

           await _context.Users.AddAsync(user);
           await _context.SaveChangesAsync();

           return user;
        }

        private void HashPassword(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var KWHash = new HMACSHA512())
            {
                passwordSalt = KWHash.Key;
                passwordHash = KWHash.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.Username == username);
        }
    }
}