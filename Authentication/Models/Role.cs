using System.ComponentModel.DataAnnotations;

namespace Authentication.Models
{
	public class Role
	{
		[Key]
		public int Id { get; set; }
		public string RoleName { get; set; }
	}
}
