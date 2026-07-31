using Microsoft.EntityFrameworkCore;

namespace Authentication.Models
{
	public class DBContext : DbContext
	{
		public DBContext(DbContextOptions<DBContext> options) : base(options) { }
		public DBContext() { }

		public virtual DbSet<User> Users { get; set; }
		public virtual DbSet<Role> Roles { get; set; }
		public virtual DbSet<UserRoles> UserRoles { get; set; }

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.Entity<UserRoles>()
				.HasKey(sc => new { sc.UserId, sc.RoleId });

			base.OnModelCreating(modelBuilder);
		}
	}
}
