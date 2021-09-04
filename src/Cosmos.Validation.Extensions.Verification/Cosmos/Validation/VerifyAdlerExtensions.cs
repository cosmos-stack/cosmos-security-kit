using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

namespace Cosmos.Validation
{
    public static class VerifyAdlerExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyAdler(this IValueRuleBuilder builder, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyAdler(this IValueRuleBuilder builder, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyAdler(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return builder.VerifyAdler(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyAdler(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler<T>(this IValueRuleBuilder<T> builder, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler<T>(this IValueRuleBuilder<T> builder, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return builder.VerifyAdler<T>(checker, type, Encoding.UTF8);
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyAdler<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, AdlerTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, AdlerTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, AdlerTypes type)
        {
            return builder.VerifyAdler<T, TVal>(checker, type, Encoding.UTF8);
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, AdlerTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }
        
        #endregion

        #region Adler32

        public static IPredicateValueRuleBuilder VerifyAdler32(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler32(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyAdler32(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValueRuleBuilder VerifyAdler32(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler32(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyAdler32(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyAdler32<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler32<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler32<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler32<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler32<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler32<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler32<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler32<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler32<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify<TVal>()(hexVal)(AdlerTypes.Adler32)(encoding)(ignoreCase)("Adler32"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler32<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler32<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler32<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));
            
            return builder.Func(AdlerHandler.CustomVerify<TVal>()(AdlerTypes.Adler32)(encoding)(checker)("Adler32"));
        }

        #endregion

        #region Adler64

        public static IPredicateValueRuleBuilder VerifyAdler64(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler64(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyAdler64(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValueRuleBuilder VerifyAdler64(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler64(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyAdler64(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler64"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler64<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler64<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler64<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler64<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler64<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyAdler64<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(AdlerHandler.CustomVerify()(AdlerTypes.Adler32)(encoding)(checker)("Adler64"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyAdler64<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(AdlerHandler.Verify<TVal>()(hexVal)(AdlerTypes.Adler64)(encoding)(ignoreCase)("Adler64"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyAdler64<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyAdler64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(AdlerHandler.CustomVerify<TVal>()(AdlerTypes.Adler32)(encoding)(checker)("Adler64"));
        }

        #endregion
    }
}