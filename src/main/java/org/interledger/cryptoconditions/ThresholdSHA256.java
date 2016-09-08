package org.interledger.cryptoconditions;

import java.util.EnumSet;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.Comparator;

import org.interledger.cryptoconditions.encoding.ConditionOutputStream;
import org.interledger.cryptoconditions.encoding.FulfillmentOutputStream;
import org.interledger.cryptoconditions.types.FulfillmentPayload;
import org.interledger.cryptoconditions.types.MessagePayload;

public class ThresholdSHA256 extends FulfillmentBase {

    private class WeightedFulfillment implements Comparable<WeightedFulfillment> {
        final int weight;
        final Fulfillment subff;
        final byte[] conditionFingerprint;
        private WeightedFulfillment(int weight, Fulfillment subfulfillment) {
            this.weight = weight;
            this.subff = subfulfillment;
            conditionFingerprint = this.subff.getCondition().getFingerprint();
        }
        
        @Override
        public int compareTo(WeightedFulfillment another) {
            if (this.conditionFingerprint.length != another.conditionFingerprint.length){
                return this.conditionFingerprint.length - another.conditionFingerprint.length;
            }
            // REF: http://stackoverflow.com/questions/5108091/java-comparator-for-byte-array-lexicographic
            // TODO: Check that this match the JS code Buffer.compare(a, b)
            int lexicoComparation = 0; // FIXME Compare lexicographically
            byte[]  left  = this.conditionFingerprint, 
                    right = another.conditionFingerprint;
            for (int idx = 0; idx < this.conditionFingerprint.length; idx++) {
                int a = (left[idx] & 0xff);
                int b = (right[idx] & 0xff);
                if (a != b) { lexicoComparation = a - b; break; }
            }
            return lexicoComparation;
        }
    }
    
    
    private class WeightAndSize implements Comparable<WeightAndSize> {
        public final int  weight;
        public final int  size;
        private WeightAndSize(int weight, int size) {
        	this.weight = weight;
        	this.size   = size;
        }

        @Override
        public int compareTo(WeightAndSize another) {
            return this.weight - another.weight;
        }
    }
   
    
    private final long threshold;
    private final List<WeightedFulfillment> subfulfillments;

    public ThresholdSHA256(ConditionType type, FulfillmentPayload payload, 
            int threshold, List<Integer>weight_l, List<Fulfillment> ff_l){
        if (weight_l.size() != ff_l.size()) {
            throw new RuntimeException("Can't zip weight_l && ff_l. Size differs ");
        }
        List<WeightedFulfillment> wff_l = new java.util.ArrayList<WeightedFulfillment>();
        for (int idx=0; idx< weight_l.size(); idx++) {
            wff_l.add(new WeightedFulfillment(weight_l.get(idx), ff_l.get(idx)));
        }
        this.threshold = threshold;
        Collections.sort(wff_l); // sort.
        this.subfulfillments = wff_l;
        throw new RuntimeException("FIXME Implement?");
    }

    @Override
    public Condition generateCondition() {
        //writeHashPayload (hasher) /* Produce the contents of the condition hash. */ {
        //  const subconditions = this.subconditions // Serialize each subcondition with weight
        //        .map((c) => { writer.writeVarUInt(c.weight),  writer.write(getConditionBinary()) })
        //  hasher.writeUInt32(this.threshold)
        //  hasher.writeVarUInt(sortedSubconditions.length)
        //  sortedSubconditions.forEach((c) => hasher.write(c))
        //}

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	byte[] fingerprint;
        try {
            ConditionOutputStream cos = new ConditionOutputStream(baos);
            cos.write32BitUInt((long)this.threshold);
            cos.writeVarUInt(this.subfulfillments.size());
            for (int idx = 0; idx < this.subfulfillments.size(); idx++) {
            	WeightedFulfillment w_ff = this.subfulfillments.get(idx);
                cos.writeVarUInt(w_ff.weight);
                cos.writeCondition(w_ff.subff.generateCondition());
            }
            fingerprint = baos.toByteArray();
            cos.close();
        } catch(Exception e){
            throw new RuntimeException(e.toString(), e);
        }
    	
        final EnumSet<FeatureSuite> BASE_FEATURES = EnumSet.of(
                FeatureSuite.SHA_256,
                FeatureSuite.THRESHOLD );
    	EnumSet<FeatureSuite> features = BASE_FEATURES;

    	int fulfillmentMaxLength = 0; // FIXME TODO
        return new ConditionImpl(
                ConditionType.THRESHOLD_SHA256,
                features,
                fingerprint,
                fulfillmentMaxLength);
    }

    @Override
    public boolean validate(MessagePayload message) {
        //validate (message) {
        //  const fulfillments = this.subconditions.filter((cond) => cond.type === FULFILLMENT)
        //
        //  let minWeight = Infinity // Find total weight and smallest individual weight
        //  const totalWeight = fulfillments.reduce((total, cond) => {
        //        minWeight = Math.min(minWeight, cond.weight)
        //        return total + cond.weight
        //  }, 0)
        //
        //  if (totalWeight < this.threshold) throw Error('Threshold not met')
        //
        //  // the set must be minimal, there mustn't be any fulfillments we could take out
        //  if (this.threshold + minWeight <= totalWeight) 
        //        throw new Error('Fulfillment is not minimal')
        //
        //  return fulfillments.every((f) => f.body.validate(message))
        //}
        throw new RuntimeException("not implemented"); // FIXME
    }

    private EnumSet<FeatureSuite>  getBitmask() { // Used to generate the Condition
      EnumSet<FeatureSuite>  result = super.getFeatures();
      for (WeightedFulfillment ff : subfulfillments ){
          EnumSet<FeatureSuite> childFeatures = ff.subff.getFeatures();
          for (FeatureSuite fs : childFeatures) {
              if (! result.contains(fs)) { result.add(fs); }
          }
      }
      return result;
    }

    /** Calculate the worst case length of a set of conditions.
    * longest possible length for valid, minimal set of subconditions. */
//    static calculateWorstCaseLength (int threshold, weight_size_l, idx = 0) {
//         if (threshold <= 0) return 0
//         if (idx > weight_size_l.length) return -Infinity
//         ws = weight_size_l[index]; size = ws.size; weight = ws.weight; idx++;
//         return Math.max(
//           size+calculateWorstCaseLength(threshold-.weight,weight_size_l,idx)
//                calculateWorstCaseLength(threshold        ,weight_size_l,idx) )
//    }

/* Calculates the longest possible fulfillment length.
 * In a threshold condition, the maximum length of the fulfillment depends on
 * the maximum lengths of the fulfillments of the subconditions. However,
 * usually not all subconditions must be fulfilled in order to meet the
 * threshold.
 * Consequently, this method relies on an algorithm to determine which
 * combination of fulfillments, where no fulfillment can be left out, results
 * in the largest total fulfillment size. */

    int calculateMaxFulfillmentLength () { // Calculate length of longest fulfillments
        int totalConditionLength = 0;
        
        List<WeightAndSize> WeightAndSize_l = new java.util.ArrayList<WeightAndSize>();
        for (int idx=0; idx < this.subfulfillments.size(); idx++){
            WeightedFulfillment wfulf = this.subfulfillments.get(idx);
            Condition   cond = this.subfulfillments.get(idx).subff.getCondition();
            int conditionLength   = -1; // FIXME ThresholdSHA256.predictSubconditionLength(cond)
            int fulfillmentLength = -1; // FIXME ThresholdSHA256.predictSubfulfillmentLength(wfulf.subff)
            totalConditionLength += conditionLength;
            WeightAndSize_l.add(
                new WeightAndSize_l(wfulf.weight, fulfillmentLength - conditionLength));
        }
        Collections.sort(WeightAndSize_l);
        int worstCaseFulfillmentsLength = totalConditionLength +
            ThresholdSHA256.calculateWorstCaseLength( this.threshold, weight_size_l);
        if (worstCaseFulfillmentsLength < 1<<30 /* FIXME In JS: -Infinity */) {
           throw new RuntimeException("Insufficient subconditions/weights to meet the threshold");
        }
        // Calculate resulting total maximum fulfillment size
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(); // FIXME JS uses a predictor that doesn't consume memory
        FulfillmentOutputStream ffos = new FulfillmentOutputStream(buffer);
        ffos.write32BitUInt(this.threshold);
        ffos.writeVarUInt(this.subfulfillments.size());
        for (int idx=0; idx< this.subfulfillments.size() ; idx++) {
            ffos.write8BitUInt(0 /*FIXME empty presence bitmask in JS*/);
            WeightedFulfillment wff = this.subfulfillments.get(idx);
            if (wff.weight != 1) ffos.write32BitUInt(wff.weight);
        }
        // Represents the sum of CONDITION/FULFILLMENT values
        // FIXME: predictor.skip(worstCaseFulfillmentsLength)
        int result = buffer.size(); 
        return result;
    }







//static predictSubconditionLength(cond){return cond.body.getConditionBinary().length}


//static predictSubfulfillmentLength (cond) {
//  const fulfillmentLength = getMaxFulfillmentLength()
//  predictor.writeUInt16()                                      // type
//  predictor.writeVarOctetString({ length: fulfillmentLength }) // payload
//  return predictor.getSize()
//}


////  selects smallest combination of fulfillments meeting a threshold.
//function calculateSmallestValidFulfillmentSet (threshold, fulfillments, state) {
//  state = state || { index: 0, size: 0, set: [] }
//  if (threshold <= 0) { return { size: state.size, set: state.set }
//  if (state.index > fulfillments.length) return { size: Infinity }
//  nextFF = fulfillments[state.index]
//  withNext = this.calculateSmallestValidFulfillmentSet(
//    threshold - nextFF.weight, fulfillments,
//    { size: state.size + nextFF.size,
//      index: state.index + 1,
//      set: state.set.concat(nextFF.index) } )
//  withoutNext = this.calculateSmallestValidFulfillmentSet(
//    threshold,                 fulfillments,
//    { size: state.size + nextFF.omitSize,
//      index: state.index + 1,
//      set: state.set } )
//  return withNext.size < withoutNext.size ? withNext : withoutNext
//}}


//writePayload (writer) { /* Generate the fulfillment OER payload to pass to the Constructor */
//  const subfulfillments = this.subconditions.map((x, i) => (
//      Object.assign({}, x, {
//        index: i,
//        size: x.body.serializeBinary().length,
//        omitSize: x.body.getConditionBinary().length
//      })
//    )
//
//  const smallestSet = this.constructor.calculateSmallestValidFulfillmentSet(
//    this.threshold, subfulfillments).set
//
//  const optimizedSubfulfillments =
//    // Take minimum set of fulfillments and turn rest into conditions
//    this.subconditions.map((c, i) => {
//      if (c.type !== FULFILLMENT || smallestSet.indexOf(i) !== -1) return c
//      return Object.assign({}, c, { type: CONDITION, body: c.body.getCondition() })
//    })
//
//  const serializedSubconditions = optimizedSubfulfillments
//    .map((cond) => {
//      const writer = new Writer()
//      writer.writeVarUInt(cond.weight)
//      writer.writeVarOctetString(cond.type === FULFILLMENT ? cond.body.serializeBinary() : EMPTY_BUFFER)
//      writer.writeVarOctetString(cond.type === CONDITION ? cond.body.serializeBinary() : EMPTY_BUFFER)
//      return writer.getBuffer()
//    })
//
//  const sortedSubconditions = this.constructor.sortBuffers(serializedSubconditions)
//
//  writer.writeVarUInt(this.threshold)
//  writer.writeVarUInt(sortedSubconditions.length)
//  sortedSubconditions.forEach(writer.write.bind(writer))
//}

