using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Validation;

namespace Cosmos.Security
{
    internal static class VerificationCoreHandler
    {
        public static Func<Func<IHashFunction>, Func<object, Func<Encoding, IHashValue>>> Hash()
            => functionFunc => o => encoding =>
            {
                var function = functionFunc();
                var bytes = VerificationHelper.ConvertToByteArray(o, encoding);
                return function.ComputeHash(bytes);
            };
        public static Func<Func<bool>, Func<string, Func<IHashValue, Func<string, CustomVerifyResult>>>> CompareAndReturn()
            => compareFunc => hexVal => hashVal => hashName =>
            {
                var compareRet = compareFunc();
                return compareRet
                    ? new CustomVerifyResult
                    {
                        VerifyResult = true
                    }
                    : new CustomVerifyResult
                    {
                        VerifyResult = false,
                        ErrorMessage = string.IsNullOrWhiteSpace(hexVal)
                            ? $"The {hashName} verification result should be {hexVal}, but the actual result is {hashVal.AsHexString()}."
                            : $"The {hashName} verification result is {hashVal.AsHexString()}, which is not the expected value."
                    };
            };
    }
}