using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

namespace Cosmos.Validation
{
    public static class VerifyMurmurHashExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifyMurmurHash(this IValueRuleBuilder builder, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMurmurHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash(this IValueRuleBuilder builder, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return builder.VerifyMurmurHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash<T>(this IValueRuleBuilder<T> builder, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMurmurHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash<T>(this IValueRuleBuilder<T> builder, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return builder.VerifyMurmurHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMurmurHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return builder.VerifyMurmurHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyMurmurHash1

        public static IPredicateValueRuleBuilder VerifyMurmurHash1(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash1(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash1(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash1(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash1<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash1<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash1<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash1<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash1<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        #endregion

        #region VerifyMurmurHash2

        public static IPredicateValueRuleBuilder VerifyMurmurHash2(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash2(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<ulong>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash2(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash2(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<ulong>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash2<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash2<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<ulong>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash2<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2<T>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash2<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<ulong>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<ulong, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return builder.VerifyMurmurHash2<T, TVal>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<ulong, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        #endregion

        #region VerifyMurmurHash3

        public static IPredicateValueRuleBuilder VerifyMurmurHash3(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash3(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash3(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder VerifyMurmurHash3(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash3<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash3<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash3<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3<T>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMurmurHash3<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MurmurHashHandler.Verify<uint, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return builder.VerifyMurmurHash3<T, TVal>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MurmurHashHandler.CustomVerify<uint, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        #endregion
    }
}