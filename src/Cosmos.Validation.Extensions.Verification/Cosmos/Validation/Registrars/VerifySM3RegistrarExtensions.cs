using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifySM3RegistrarExtensions
    {
        public static IPredicateValidationRegistrar VerifySM3(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySM3(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifySM3(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(Sm3Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValidationRegistrar VerifySM3(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySM3(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifySM3(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(Sm3Handler.CustomVerify()(encoding)(checker));
        }

        public static IPredicateValidationRegistrar<T> VerifySM3<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySM3<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifySM3<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(Sm3Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValidationRegistrar<T> VerifySM3<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySM3<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifySM3<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(Sm3Handler.CustomVerify()(encoding)(checker));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySM3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifySM3<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySM3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(Sm3Handler.Verify<TVal>()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySM3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifySM3<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifySM3<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(Sm3Handler.CustomVerify<TVal>()(encoding)(checker));
        }
    }
}