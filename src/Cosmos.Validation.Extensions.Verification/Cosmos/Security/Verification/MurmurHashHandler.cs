using System;
using System.Text;
using Cosmos.Optionals;
using Cosmos.Text;
using Cosmos.Validation;

namespace Cosmos.Security.Verification
{
    internal static class MurmurHashHandler
    {
        public static Func<string, Func<Func<IMurmurHash>, Func<Encoding, Func<IgnoreCase, Func<string, Func<object, CustomVerifyResult>>>>>> Verify<TSeed>(TSeed seed)
            => hexVal => functionFunc => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(functionFunc)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<Func<IMurmurHash>, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<object, CustomVerifyResult>>>>> CustomVerify<TSeed>(TSeed seed)
            => functionFunc => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(functionFunc)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };

        public static Func<string, Func<MurmurHashTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<object, CustomVerifyResult>>>>>> Verify()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => MurmurHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<MurmurHashTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<object, CustomVerifyResult>>>>> CustomVerify()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => MurmurHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };

        public static Func<string, Func<Func<IMurmurHash>, Func<Encoding, Func<IgnoreCase, Func<string, Func<TVal, CustomVerifyResult>>>>>> Verify<TSeed, TVal>(TSeed seed)
            => hexVal => functionFunc => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(functionFunc)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<Func<IMurmurHash>, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<TVal, CustomVerifyResult>>>>> CustomVerify<TSeed, TVal>(TSeed seed)
            => functionFunc => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(functionFunc)(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };

        public static Func<string, Func<MurmurHashTypes, Func<Encoding, Func<IgnoreCase, Func<string, Func<TVal, CustomVerifyResult>>>>>> Verify<TVal>()
            => hexVal => type => encoding => ignoreCase => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => MurmurHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(
                    () => 0 == VerificationHelper.Compare(hexVal, hashVal.GetHexString(), ignoreCase))(hexVal)(hashVal)(hashName);
            };

        public static Func<MurmurHashTypes, Func<Encoding, Func<Func<IHashValue, bool>, Func<string, Func<TVal, CustomVerifyResult>>>>> CustomVerify<TVal>()
            => type => encoding => checker => hashName => o =>
            {
                var hashVal = VerificationCoreHandler.Hash()(() => MurmurHashFactory.Create(type))(o)(encoding.SafeEncodingValue());
                return VerificationCoreHandler.CompareAndReturn()(() => checker(hashVal))(null)(hashVal)(hashName);
            };
    }
}