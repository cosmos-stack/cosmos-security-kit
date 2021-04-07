using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Security.Verification.Adler;
using Cosmos.Text;
using EnumsNET;

namespace Cosmos.Validation.Registrars
{
    public static class VerifyAdlerRegistrarExtensions
    {
        #region Common Entry

        public static IPredicateValidationRegistrar VerifyAdler(this IValueFluentValidationRegistrar registrar, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyAdler(this IValueFluentValidationRegistrar registrar, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyAdler(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return registrar.VerifyAdler(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyAdler(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return registrar.VerifyAdler<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return registrar.VerifyAdler<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region Adler32

        public static IPredicateValidationRegistrar VerifyAdler32(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler32(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyAdler32(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValidationRegistrar VerifyAdler32(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler32(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyAdler32(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler32<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler32<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler32<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler32<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler32<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler32<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler32<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler32<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler32<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify<TVal>()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler32<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler32<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler32<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify<TVal>()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }

        #endregion

        #region Adler64

        public static IPredicateValidationRegistrar VerifyAdler64(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler64(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyAdler64(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValidationRegistrar VerifyAdler64(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler64(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyAdler64(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler64)(encoding)(checker)("Adler64"));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler64<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler64<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler64<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler64<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler64<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyAdler64<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler64"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler64<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyAdler64<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler64<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(AdlerHandler.Verify<TVal>()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler64<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyAdler64<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyAdler64<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(AdlerHandler.CustomVerify<TVal>()(AdlerTypes.Adler32)(encoding)(checker)("Adler64"));
        }

        #endregion
    }
}