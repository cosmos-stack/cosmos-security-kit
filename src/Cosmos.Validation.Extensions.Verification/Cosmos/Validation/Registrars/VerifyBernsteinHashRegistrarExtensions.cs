using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyBernsteinHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyBernsteinHash(this IValueFluentValidationRegistrar registrar, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBernsteinHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyBernsteinHash(this IValueFluentValidationRegistrar registrar, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyBernsteinHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return registrar.VerifyBernsteinHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyBernsteinHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyBernsteinHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBernsteinHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyBernsteinHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyBernsteinHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return registrar.VerifyBernsteinHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyBernsteinHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, BernsteinHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBernsteinHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, BernsteinHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type)
        {
            return registrar.VerifyBernsteinHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBernsteinHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, BernsteinHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyTime33

        public static IPredicateValidationRegistrar VerifyTime33(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyTime33(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyTime33(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValidationRegistrar VerifyTime33(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyTime33(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyTime33(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        public static IPredicateValidationRegistrar<T> VerifyTime33<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyTime33<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyTime33<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValidationRegistrar<T> VerifyTime33<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyTime33<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyTime33<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyTime33<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyTime33<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyTime33<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BernsteinHashHandler.Verify<TVal>()(hexVal)(BernsteinHashTypes.Time33)(encoding)(ignoreCase)("Time33"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyTime33<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyTime33<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyTime33<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BernsteinHashHandler.CustomVerify<TVal>()(BernsteinHashTypes.Time33)(encoding)(checker)("Time33"));
        }

        #endregion
    }
}