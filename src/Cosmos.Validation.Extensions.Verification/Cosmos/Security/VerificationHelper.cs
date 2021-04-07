using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Text;

namespace Cosmos.Security
{
    internal static class VerificationHelper
    {
        public static byte[] ConvertToByteArray(object obj, Encoding encoding = null)
        {
            if (obj is null)
                return new byte[0];

            encoding = encoding.SafeEncodingValue();

            if (obj is string str)
                return encoding.GetBytes(str);

            if (obj is byte[] bytes)
                return bytes;

            //检查 FileInfo， 对 FileInfo 对应的文件进行取样
            //该功能尚未实现

            return encoding.GetBytes(obj.ToString() ?? string.Empty);
        }

        public static int Compare(string a, string b, IgnoreCase ignoreCase)
        {
            if (ignoreCase == IgnoreCase.FALSE)
                return string.Compare(a, b, StringComparison.Ordinal);
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }
    }
}