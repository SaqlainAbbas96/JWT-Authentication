using Authentication.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Infrastructure.Persistence
{
	public class DBContext : DbContext
	{
		public DBContext(DbContextOptions<DBContext> options) : base(options) { }
		public DBContext() { }

		public virtual DbSet<User> users { get; set; }
		public virtual DbSet<Role> roles { get; set; }
		public virtual DbSet<UserRoles> user_roles { get; set; }

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.Entity<UserRoles>()
				.HasKey(sc => new { sc.user_id, sc.role_id });

			base.OnModelCreating(modelBuilder);
		}
	}
}
