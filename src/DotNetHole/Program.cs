using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;

namespace DotNetHole
{
	public class Program
	{
		public static void Main(string[] args)
		{
			var dotNetHoleService = new DotNetHoleService();

			if (!IsConsoleWindow())
			{
				ServiceBase.Run(dotNetHoleService);
				return;
			}

			dotNetHoleService.Start();

			Console.CancelKeyPress += (sender, eventArgs) =>
			{
				dotNetHoleService.Stop();
				Process.GetCurrentProcess().Kill();
			};

			while (true)
				Console.ReadKey();
		}

		private static bool IsConsoleWindow()
		{
			try
			{
				var _ = Console.WindowWidth;
				return true;
			}
			catch (IOException)
			{
				return false;
			}
		}
	}

	public class DotNetHoleService : ServiceBase
	{
		private const bool SimpleLogging = true;
		private DnsClient _client;

		private readonly HashSet<string> _blacklistedUrls = new HashSet<string>();
		private readonly SemaphoreSlim _logSemaphore = new SemaphoreSlim(1, 1);

		private long _blockCount;
		private long _totalCount;
		private DnsServer _server;
		private bool _isService;

		protected override async void OnStart(string[] args)
		{
			_isService = true;
			await Start();
			base.OnStart(args);
		}

		protected override void OnStop()
		{
			_server.Stop();
			base.OnStop();
		}

		protected override void OnPause()
		{
			_server.Stop();
			base.OnPause();
		}

		protected override void OnContinue()
		{
			_server.Start();
			base.OnContinue();
		}

		public async Task Start()
		{
			await LoadBlacklist();

			LogToConsole($"Blacklisted domains: {_blacklistedUrls.Count}");

			_client = new DnsClient(IPAddress.Parse("1.1.1.1"), 200);

			_server = new DnsServer(10, 10);
			_server.QueryReceived += ServerOnQueryReceived;
			_server.Start();
		}

		private async Task LoadBlacklist()
		{
			var applicationDirectory = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
			var blacklistsFilePath = Path.Combine(applicationDirectory, "blacklists.txt");
			if (!File.Exists(blacklistsFilePath))
				throw new FileNotFoundException($"Blacklists file not found at path: {blacklistsFilePath}");

			var blacklistFileUrls = await File.ReadAllLinesAsync(blacklistsFilePath);
			using var httpClient = new HttpClient();

			foreach (var url in blacklistFileUrls)
			{
				string blacklistContent;
				try
				{
					blacklistContent = await httpClient.GetStringAsync(url);
				}
				catch (Exception)
				{
					LogToConsole($"Blacklist {url} failed to load.", true);
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
			if (!(eventargs.Query is DnsMessage dnsMessage)) return;

			var isBlacklisted = IsBlacklisted(dnsMessage);
			var response = await _client.SendMessageAsync(dnsMessage);

			if (!isBlacklisted)
				eventargs.Response = response;
			else
			{
				var newMessage = ReplaceARecords(response, dnsMessage);

				eventargs.Response = newMessage;
			}

			if (_isService)
				return;

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
			var percentage = Math.Round((double) _blockCount / _totalCount * 100, 2);
			var logMessage = $"Block count: {_blockCount}/{_totalCount} ({percentage}%)";

			LogToConsole($"{logMessage}          ", false, true);
		}

		private void LogQueryFull(DnsMessage questionMessage, DnsMessage responseMessage, bool isBlacklisted)
		{
			LogToConsole(questionMessage.Questions.First().Name, red: isBlacklisted);
			foreach (var answer in responseMessage.AnswerRecords)
			{
				switch (answer)
				{
					case AddressRecordBase addressRecordBase:
						LogToConsole($"\t{addressRecordBase.Address}", red: isBlacklisted);
						break;
				}
			}
		}

		private void LogToConsole(object message, bool red = false, bool overwrite = false)
		{
			if (_isService)
				return;

			if (red)
				Console.ForegroundColor = ConsoleColor.Red;

			if (overwrite)
				Console.SetCursorPosition(0, 0);

			Console.WriteLine(message);

			if (red)
				Console.ResetColor();
		}
	}
}