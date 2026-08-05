using System.ComponentModel.DataAnnotations;

namespace Authentication.Domain.Entities
{
	public class Role
	{
		[Key]
		public int id { get; set; }
		public string role_name { get; set; }
	}
}
