using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Text;
using Cosmos.Validation;

namespace Cosmos.Security.Verification
{
    internal static class PearsonHandler
    {
        public static Func<string, Func<Encoding, Func<IgnoreCase, Func<object, CustomVerifyResult>>>> Verify()
            => hexVal =>  encoding => ignoreCase => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(PearsonFactory.Create)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)("SM3");
            };

        public static Func<Encoding, Func<Func<IHashValue, bool>, Func<object, CustomVerifyResult>>> CustomVerify()
            => encoding => checker => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(PearsonFactory.Create)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)("SM3");
            };
        
        public static Func<string, Func<Encoding, Func<IgnoreCase, Func<TVal, CustomVerifyResult>>>> Verify<TVal>()
            => hexVal =>  encoding => ignoreCase => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(PearsonFactory.Create)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)("SM3");
            };

        public static Func<Encoding, Func<Func<IHashValue, bool>, Func<TVal, CustomVerifyResult>>> CustomVerify<TVal>()
            => encoding => checker => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(PearsonFactory.Create)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)("SM3");
            };
    }
}