using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyBuzHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyBuzHash(this IValueFluentValidationRegistrar registrar, string hexVal, BuzHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBuzHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyBuzHash(this IValueFluentValidationRegistrar registrar, string hexVal, BuzHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BuzHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyBuzHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, BuzHashTypes type)
        {
            return registrar.VerifyBuzHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyBuzHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, BuzHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BuzHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyBuzHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, BuzHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBuzHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyBuzHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, BuzHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BuzHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyBuzHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, BuzHashTypes type)
        {
            return registrar.VerifyBuzHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyBuzHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, BuzHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BuzHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBuzHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, BuzHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyBuzHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBuzHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, BuzHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(BuzHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBuzHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, BuzHashTypes type)
        {
            return registrar.VerifyBuzHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyBuzHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, BuzHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(BuzHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}