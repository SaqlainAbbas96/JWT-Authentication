using System.ComponentModel.DataAnnotations;

namespace Authentication.Models
{
	public class User
	{
        [Key]
        public int Id { get; set; }
        public string Email { get; set; }
		public byte[] PasswordHash { get; set; }
		public byte[] PasswordSalt { get; set; }
	}
}
