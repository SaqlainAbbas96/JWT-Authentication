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
        public virtual DbSet<RefreshToken> refresh_tokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
            modelBuilder.Entity<UserRoles>()
            .HasKey(sc => new
            {
                sc.user_id,
                sc.role_id
            });

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.token_hash)
                .IsUnique();

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.family_id);

            modelBuilder.Entity<RefreshToken>()
                .HasIndex(rt => rt.expires_at);

            modelBuilder.Entity<RefreshToken>()
                .HasOne<User>()
                .WithMany()
                .HasForeignKey(rt => rt.user_id)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RefreshToken>()
                .HasOne<RefreshToken>()
                .WithMany()
                .HasForeignKey(rt => rt.replaced_by_token_id)
                .OnDelete(DeleteBehavior.Restrict);

            base.OnModelCreating(modelBuilder);
		}
	}
}
