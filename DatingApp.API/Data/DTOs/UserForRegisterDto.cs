using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Data.DTOs
{
    public class UserForRegisterDto
    {
        [Required]
        public string Username { get; set; }

        [Required]
        [StringLength(8, MinimumLength = 6, ErrorMessage = "Password must be less than 8 characters and greater than 6 characters.")]
        public string Password { get; set; }
    }
}