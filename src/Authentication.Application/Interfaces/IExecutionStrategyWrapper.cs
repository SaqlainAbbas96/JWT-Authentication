namespace Authentication.Application.Interfaces
{
    public interface IExecutionStrategyWrapper
    {
        Task ExecuteAsync(
            Func<CancellationToken, Task> operation,
            CancellationToken cancellationToken);

        Task<T> ExecuteAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            CancellationToken cancellationToken);
    }
}
