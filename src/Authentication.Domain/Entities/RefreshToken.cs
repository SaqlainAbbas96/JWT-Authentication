using System.ComponentModel.DataAnnotations;

namespace Authentication.Domain.Entities
{
    public sealed class RefreshToken
    {
        [Key]
        public int id { get; set; }

        public int user_id { get; set; }

        public string token_hash { get; set; }

        public Guid family_id { get; set; }

        public DateTime created_at { get; set; }

        public DateTime expires_at { get; set; }

        public DateTime? revoked_at { get; set; }

        public int? replaced_by_token_id { get; set; }
    }
}
