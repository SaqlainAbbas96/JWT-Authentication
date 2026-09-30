using Authentication.Application.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Infrastructure.Persistence
{
    public sealed class ExecutionStrategyWrapper : IExecutionStrategyWrapper
    {
        private readonly DBContext _db;

        public ExecutionStrategyWrapper(DBContext db)
        {
            _db = db;
        }

        public async Task ExecuteAsync(
            Func<CancellationToken, Task> operation,
            CancellationToken cancellationToken)
        {
            var strategy =
                _db.Database.CreateExecutionStrategy();

            await strategy.ExecuteAsync(
                async () =>
                {
                    await operation(cancellationToken);
                });
        }

        public async Task<T> ExecuteAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            CancellationToken cancellationToken)
        {
            var strategy =
                _db.Database.CreateExecutionStrategy();

            return await strategy.ExecuteAsync(
                async () =>
                    await operation(cancellationToken));
        }
    }
}
