using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyMetroHashRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyMetroHash(this IValueFluentValidationRegistrar registrar, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMetroHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMetroHash(this IValueFluentValidationRegistrar registrar, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MetroHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyMetroHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return registrar.VerifyMetroHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMetroHash(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MetroHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMetroHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMetroHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMetroHash<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MetroHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMetroHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return registrar.VerifyMetroHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMetroHash<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MetroHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMetroHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MetroHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMetroHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMetroHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MetroHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MetroHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMetroHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MetroHashTypes type)
        {
            return registrar.VerifyMetroHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMetroHash<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MetroHashTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MetroHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}