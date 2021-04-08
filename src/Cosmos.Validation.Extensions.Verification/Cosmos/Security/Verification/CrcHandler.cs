using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Security.Verification.CRC;
using Cosmos.Text;
using Cosmos.Validation;

namespace Cosmos.Security.Verification
{
    internal static class CrcHandler
    {
        public static Func<string, Func<CrcTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<object, CustomVerifyResult>>>>>> Verify()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => CrcFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.AsHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<CrcTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<object, CustomVerifyResult>>>>> CustomVerify()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => CrcFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };
        
        public static Func<string, Func<CrcTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<TVal, CustomVerifyResult>>>>>> Verify<TVal>()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => CrcFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.AsHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<CrcTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<TVal, CustomVerifyResult>>>>> CustomVerify<TVal>()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => CrcFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };
    }
}