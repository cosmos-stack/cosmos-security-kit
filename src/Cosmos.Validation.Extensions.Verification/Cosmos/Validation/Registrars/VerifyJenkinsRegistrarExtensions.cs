using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyJenkinsRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyJenkins(this IValueFluentValidationRegistrar registrar, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyJenkins(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyJenkins(this IValueFluentValidationRegistrar registrar, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(JenkinsHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyJenkins(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return registrar.VerifyJenkins(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyJenkins(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(JenkinsHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyJenkins<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyJenkins<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyJenkins<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(JenkinsHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyJenkins<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return registrar.VerifyJenkins<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyJenkins<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(JenkinsHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyJenkins<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyJenkins<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyJenkins<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(JenkinsHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyJenkins<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return registrar.VerifyJenkins<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyJenkins<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(JenkinsHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}