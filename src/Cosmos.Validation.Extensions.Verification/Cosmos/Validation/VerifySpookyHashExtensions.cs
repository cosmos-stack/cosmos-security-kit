using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifySpookyHashExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifySpookyHash(this IValueRuleBuilder builder, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySpookyHash(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySpookyHash(this IValueRuleBuilder builder, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(SpookyHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifySpookyHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return builder.VerifySpookyHash(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySpookyHash(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(SpookyHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifySpookyHash<T>(this IValueRuleBuilder<T> builder, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySpookyHash<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySpookyHash<T>(this IValueRuleBuilder<T> builder, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(SpookyHashHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifySpookyHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return builder.VerifySpookyHash<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySpookyHash<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(SpookyHashHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifySpookyHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, SpookyHashTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySpookyHash<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySpookyHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, SpookyHashTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(SpookyHashHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySpookyHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, SpookyHashTypes type)
        {
            return builder.VerifySpookyHash<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySpookyHash<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, SpookyHashTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(SpookyHashHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}