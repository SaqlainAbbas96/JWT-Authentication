using System.ComponentModel.DataAnnotations;

namespace Authentication.Models.Dtos
{
	public class UserDto
	{
		[Required]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		public string Password { get; set; }
	}
}
