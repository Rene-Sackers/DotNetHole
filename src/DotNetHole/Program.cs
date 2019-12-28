using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;

namespace DotNetHole
{
	public class Program
	{
		public static async Task Main()
		{
			await new ProgramInstance().Run();
			Process.GetCurrentProcess().Kill();
		}
	}

	public class ProgramInstance
	{
		private const bool SimpleLogging = true;
		private DnsClient _client;

		private readonly TaskCompletionSource<object> _taskCompletionSource = new TaskCompletionSource<object>();
		private readonly HashSet<string> _blacklistedUrls = new HashSet<string>();
		private readonly SemaphoreSlim _logSemaphore = new SemaphoreSlim(1, 1);

		private long _blockCount;
		private long _totalCount;

		public async Task Run()
		{
			await LoadBlacklist();

			Console.WriteLine($"Blacklisted domains: {_blacklistedUrls.Count}");

			_client = new DnsClient(IPAddress.Parse("1.1.1.1"), 200);

			Console.Clear();

			var server = new DnsServer(10, 10);
			server.QueryReceived += ServerOnQueryReceived;
			server.Start();

			Console.CancelKeyPress += (sender, eventArgs) =>
			{
				server.Stop();
				_taskCompletionSource.SetResult(null);
			};

			await _taskCompletionSource.Task;
		}

		private async Task LoadBlacklist()
		{
			var blacklistFileUrls = await File.ReadAllLinesAsync("blacklists.txt");
			using var httpClient = new HttpClient();

			foreach (var url in blacklistFileUrls)
			{
				string blacklistContent;
				try
				{
					blacklistContent = (await httpClient.GetStringAsync(url));
				}
				catch (Exception)
				{
					Console.WriteLine($"Blacklist {url} failed to load.");
					continue;
				}

				if (string.IsNullOrWhiteSpace(blacklistContent))
					continue;

				foreach (var blacklistedUrl in blacklistContent.Split('\n'))
				{
					var trimmedUrl = blacklistedUrl.Trim();
					if (!_blacklistedUrls.Contains(trimmedUrl))
						_blacklistedUrls.Add(trimmedUrl);
				}
			}
		}

		private bool IsBlacklisted(DnsMessage requestMessage) =>
			requestMessage.Questions.Any(q => _blacklistedUrls.Contains(q.Name.ToString().Trim('.')));

		private async Task ServerOnQueryReceived(object sender, QueryReceivedEventArgs eventargs)
		{
			if (!(eventargs.Query is DnsMessage dnsMessage))
			{
				return;
			}

			var isBlacklisted = IsBlacklisted(dnsMessage);
			var response = await _client.SendMessageAsync(dnsMessage);

			if (!isBlacklisted)
			{
				eventargs.Response = response;
			}
			else
			{
				var newMessage = ReplaceARecords(response, dnsMessage);

				eventargs.Response = newMessage;
			}

#pragma warning disable 4014
			LogQuery(dnsMessage, (DnsMessage) eventargs.Response, isBlacklisted);
#pragma warning restore 4014
		}

		private static DnsMessage ReplaceARecords(DnsMessage response, DnsMessage dnsMessage)
		{
			var newRecords = new List<DnsRecordBase>();
			foreach (var answerRecord in response.AnswerRecords)
			{
				switch (answerRecord)
				{
					case ARecord _:
						var newARecord = new ARecord(answerRecord.Name, answerRecord.TimeToLive, IPAddress.Loopback);
						newRecords.Add(newARecord);
						break;
					case AaaaRecord _:
						var newAaaaRecord = new AaaaRecord(answerRecord.Name, answerRecord.TimeToLive, IPAddress.IPv6Loopback);
						newRecords.Add(newAaaaRecord);
						break;
					default:
						newRecords.Add(answerRecord);
						break;
				}
			}

			return new DnsMessage
			{
				Questions = dnsMessage.Questions,
				IsQuery = false,
				AdditionalRecords = response.AdditionalRecords,
				AnswerRecords = newRecords,
				AuthorityRecords = response.AuthorityRecords,
				EDnsOptions = response.EDnsOptions,
				IsAuthenticData = response.IsAuthenticData,
				IsAuthoritiveAnswer = response.IsAuthoritiveAnswer,
				IsCheckingDisabled = response.IsCheckingDisabled,
				IsDnsSecOk = response.IsDnsSecOk,
				IsEDnsEnabled = response.IsAuthenticData,
				IsRecursionAllowed = response.IsRecursionAllowed,
				IsRecursionDesired = response.IsRecursionDesired,
				IsTruncated = response.IsTruncated,
				OperationCode = response.OperationCode,
				ReturnCode = response.ReturnCode,
				TSigOptions = response.TSigOptions,
				TransactionID = response.TransactionID
			};
		}

		private async Task LogQuery(DnsMessage questionMessage, DnsMessage responseMessage, bool isBlacklisted)
		{
			await _logSemaphore.WaitAsync();

			_totalCount++;
			if (isBlacklisted)
				_blockCount++;


			if (SimpleLogging)
				LogQuerySimple();
			else
				LogQueryFull(questionMessage, responseMessage, isBlacklisted);


			_logSemaphore.Release();
		}

		private void LogQuerySimple()
		{
			var percentage = Math.Round((double)_blockCount / _totalCount * 100, 2);
			var logMessage = $"Block count: {_blockCount}/{_totalCount} ({percentage}%)";

			Console.Title = logMessage;

			Console.SetCursorPosition(0, 0);
			Console.WriteLine($"{logMessage}          ");
		}

		private static void LogQueryFull(DnsMessage questionMessage, DnsMessage responseMessage, bool isBlacklisted)
		{
			if (isBlacklisted || responseMessage == null)
			{
				Console.ForegroundColor = ConsoleColor.Red;
			}

			Console.WriteLine(questionMessage.Questions.First().Name);
			foreach (var answer in responseMessage.AnswerRecords)
			{
				switch (answer)
				{
					case AddressRecordBase addressRecordBase:
						Console.WriteLine($"\t{addressRecordBase.Address}");
						break;
				}
			}

			Console.ResetColor();
		}
	}
}
