using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyJenkinsExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifyJenkins(this IValueRuleBuilder builder, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyJenkins(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyJenkins(this IValueRuleBuilder builder, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(JenkinsHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyJenkins(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return builder.VerifyJenkins(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyJenkins(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(JenkinsHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyJenkins<T>(this IValueRuleBuilder<T> builder, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyJenkins<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyJenkins<T>(this IValueRuleBuilder<T> builder, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(JenkinsHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyJenkins<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return builder.VerifyJenkins<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyJenkins<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(JenkinsHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyJenkins<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, JenkinsTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyJenkins<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyJenkins<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, JenkinsTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(JenkinsHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyJenkins<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, JenkinsTypes type)
        {
            return builder.VerifyJenkins<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyJenkins<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, JenkinsTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(JenkinsHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}