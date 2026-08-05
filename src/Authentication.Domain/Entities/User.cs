using System.ComponentModel.DataAnnotations;

namespace Authentication.Domain.Entities
{
	public class User
	{
        [Key]
        public int id { get; set; }
        public string email { get; set; }
		public byte[] password_hash { get; set; }
		public byte[] password_salt { get; set; }
	}
}
