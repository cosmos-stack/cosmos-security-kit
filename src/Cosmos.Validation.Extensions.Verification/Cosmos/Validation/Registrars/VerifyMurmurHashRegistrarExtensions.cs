using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

namespace Cosmos.Validation.Registrars
{
    public static class VerifyMurmurHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyMurmurHash(this IValueFluentValidationRegistrar registrar, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMurmurHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash(this IValueFluentValidationRegistrar registrar, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return registrar.VerifyMurmurHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMurmurHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return registrar.VerifyMurmurHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MurmurHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMurmurHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MurmurHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MurmurHashTypes type)
        {
            return registrar.VerifyMurmurHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MurmurHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyMurmurHash1

        public static IPredicateValidationRegistrar VerifyMurmurHash1(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash1(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash1(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash1(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash1<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash1<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash1<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash1<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash1"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash1<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash1<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash1Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash1"));
        }

        #endregion

        #region VerifyMurmurHash2

        public static IPredicateValidationRegistrar VerifyMurmurHash2(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash2(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<ulong>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash2(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash2(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<ulong>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash2<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash2<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<ulong>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash2<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2<T>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash2<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<ulong>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<ulong, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash2"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, ulong seed = 0UL)
        {
            return registrar.VerifyMurmurHash2<T, TVal>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding, ulong seed = 0UL)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<ulong, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash2Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash2"));
        }

        #endregion

        #region VerifyMurmurHash3

        public static IPredicateValidationRegistrar VerifyMurmurHash3(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash3(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash3(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar VerifyMurmurHash3(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash3<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3<T>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash3<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash3<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3<T>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar<T> VerifyMurmurHash3<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3<T, TVal>(hexVal, Encoding.UTF8, ignoreCase, seed);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MurmurHashHandler.Verify<uint, TVal>(seed)(hexVal)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(ignoreCase)("MurmurHash3"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, uint seed = 0U)
        {
            return registrar.VerifyMurmurHash3<T, TVal>(checker, Encoding.UTF8, seed);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMurmurHash3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding, uint seed = 0U)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MurmurHashHandler.CustomVerify<uint, TVal>(seed)(() => MurmurHashFactory.Create((MurmurHash3Config config) => config.Seed = seed))(encoding)(checker)("MurmurHash3"));
        }

        #endregion
    }
}