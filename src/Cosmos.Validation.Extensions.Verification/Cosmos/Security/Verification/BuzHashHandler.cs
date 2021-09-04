using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Text;
using Cosmos.Validation;

namespace Cosmos.Security.Verification
{
    internal static class BuzHashHandler
    {
        public static Func<string, Func<BuzHashTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<object, CustomVerifyResult>>>>>> Verify()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => BuzHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<BuzHashTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<object, CustomVerifyResult>>>>> CustomVerify()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => BuzHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };
        
        public static Func<string, Func<BuzHashTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<TVal, CustomVerifyResult>>>>>> Verify<TVal>()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => BuzHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<BuzHashTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<TVal, CustomVerifyResult>>>>> CustomVerify<TVal>()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => BuzHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };
    }
}