using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Data.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _auth;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository auth, IConfiguration config)
        {
            _auth = auth;
            _config = config;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(UserForRegisterDto userDto)
        {
            userDto.Username = userDto.Username.ToLower();

            if(await _auth.UserExists(userDto.Username))
                return BadRequest("User already exists!");
            
            var UserToCreate = new User {
                Username = userDto.Username
            };

            var CreatedUser = await _auth.Register(UserToCreate,userDto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var LoggedInUserDto = await _auth.Login(userForLoginDto.Username.ToLower(),userForLoginDto.Password);
            
            if(LoggedInUserDto == null)
                return Unauthorized();
            
            var claims = new []
            {
                new Claim(ClaimTypes.NameIdentifier,LoggedInUserDto.Id.ToString()),
                new Claim(ClaimTypes.Name, userForLoginDto.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var desc = new SecurityTokenDescriptor{
                Expires = System.DateTime.Now.AddDays(1),
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = creds,
                IssuedAt = System.DateTime.Now,
                NotBefore = System.DateTime.Now
            };

            var handler = new JwtSecurityTokenHandler();

            var token = handler.CreateToken(desc);

            return Ok(new {
                token = handler.WriteToken(token)});
        }
    }
}